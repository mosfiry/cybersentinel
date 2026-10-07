"""Contract tests for the bundled Windows Desktop application."""
from __future__ import annotations

import json
from pathlib import Path

MAIN = Path("desktop/main.js").read_text(encoding="utf-8")
PRELOAD = Path("desktop/preload.js").read_text(encoding="utf-8")
UNAVAILABLE = Path("desktop/unavailable.html").read_text(encoding="utf-8")
PACKAGE = json.loads(Path("desktop/package.json").read_text(encoding="utf-8"))
WORKFLOW = Path(".github/workflows/desktop-build.yml").read_text(encoding="utf-8")
APP = Path("web/app.js").read_text(encoding="utf-8")
BRIDGE = Path("bridge.py").read_text(encoding="utf-8")


def test_packaged_shell_starts_bundled_backend_without_external_python_or_repository():
    assert 'if (app.isPackaged) return null;' in MAIN
    assert 'path.join(process.resourcesPath, "backend", "cybersentinel-backend.exe")' in MAIN
    assert 'args = ["--desktop-stdio-control"]' in MAIN
    assert 'if (!app.isPackaged)' in MAIN
    assert 'process.env.CYBERSENTINEL_PYTHON || "python"' in MAIN  # development-only path
    assert "CYBERSENTINEL_REPO" not in MAIN
    assert "developer_repository_missing" in MAIN
    assert 'env.BRIDGE_HOST = "127.0.0.1"' in MAIN
    assert "findFreeLoopbackPort" in MAIN
    assert 'mainWindow.loadURL(`${appOrigin()}/`)' in MAIN


def test_backend_and_persistent_state_are_bundled_or_scoped_to_user_data():
    assert 'path.join(process.resourcesPath, "llama")' in MAIN
    assert 'app.getPath("userData")' in MAIN
    assert 'path.join(root, "local-model-manager")' in MAIN
    assert 'path.join(state, "intel.sqlite3")' in MAIN
    assert 'env.CYBERSENTINEL_DESKTOP_MODE = "true"' in MAIN
    assert 'env.CYBERSENTINEL_DESKTOP_SETUP_TOKEN = desktopSetupToken' in MAIN
    assert 'env.BRIDGE_TOKEN = bridgeToken' in MAIN
    assert "bridgeProcess.stdout.resume()" in MAIN
    assert "bridgeProcess.stderr.resume()" in MAIN
    assert "process.stdout.write(`[bridge]" not in MAIN
    assert '"BRIDGE_TOKEN"' not in PRELOAD
    assert '"CYBERSENTINEL_DESKTOP_SETUP_TOKEN"' not in PRELOAD
    assert '"node:fs"' not in PRELOAD
    assert "contextIsolation: true" in MAIN
    assert "nodeIntegration: false" in MAIN
    assert "sandbox: true" in MAIN


def test_first_run_owner_bootstrap_is_one_time_and_keeps_credentials_out_of_storage():
    assert '"desktop:create-owner"' in MAIN
    assert "postOwnerBootstrap(payload.password)" in MAIN
    assert '"X-CyberSentinel-Setup-Key": desktopSetupToken' in MAIN
    assert 'if owner_password.owner_account_exists():' in BRIDGE
    assert 'path == "/api/desktop/bootstrap-owner"' in BRIDGE
    assert 'create_owner_account(owner_password.OWNER_USERNAME, password)' in BRIDGE
    assert 'id="ownerSetupForm"' in Path("web/index.html").read_text(encoding="utf-8")
    assert "window.cybersentinelDesktop.createOwner(password)" in APP
    assert "localStorage" not in APP
    assert "sessionStorage" not in APP
    assert '"CYBERSENTINEL_REPO"' not in UNAVAILABLE
    assert "Python مثبت" not in UNAVAILABLE
    assert "إعادة المحاولة" in UNAVAILABLE


def test_project_folder_import_uses_native_dialog_csrf_owner_and_capability():
    assert "dialog.showOpenDialog(mainWindow" in MAIN
    assert '"X-CSRF-Token": payload.csrfToken' in MAIN
    assert '"X-CyberSentinel-Desktop-Capability": desktopSetupToken' in MAIN
    assert 'path == "/api/public/projects/import"' in BRIDGE
    assert "native_folder_selection_required" in BRIDGE
    assert 'selected_root=payload.get("selected_root")' in BRIDGE
    assert "window.cybersentinelDesktop.selectProjectFolder" in APP
    assert "mission.project_id === state.activeProjectId" in APP


def test_local_model_catalog_downloader_and_runtime_are_pinned_and_loopback_only():
    catalog = json.loads(Path("agent/local_runtime/catalog.json").read_text(encoding="utf-8"))
    catalog_module = Path("agent/local_runtime/catalog.py").read_text(encoding="utf-8")
    downloader = Path("agent/local_runtime/downloader.py").read_text(encoding="utf-8")
    runtime = Path("agent/local_runtime/runtime.py").read_text(encoding="utf-8")
    manager = Path("agent/local_runtime/manager.py").read_text(encoding="utf-8")
    models = {item["model_id"]: item for item in catalog["models"]}
    assert "Qwen3-4B-Q4_K_M.gguf" == models["qwen3-4b-q4-k-m"]["filename"]
    assert "qwen3-8b-q4_k_m.gguf" == models["qwen3-8b-q4-k-m"]["filename"]
    assert "DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf" == models["deepseek-r1-distill-qwen-7b-q4-k-m"]["filename"]
    assert all(item["revision"] and len(item["sha256"]) == 64 for item in models.values())
    assert all(item["backend_compatibility"] and item["license_url"].startswith("https://") for item in models.values())
    assert "load_catalog" in catalog_module
    assert '("huggingface.co", "hf.co")' in downloader
    assert "expected_sha256" in downloader
    assert "os.replace(part, target)" in downloader
    assert '"127.0.0.1"' in runtime
    assert '"--api-key"' in runtime
    assert "RuntimeAdapter" in runtime
    assert "model_not_compatible" in manager
    assert '"model_manager_busy"' in manager
    assert 'status="interrupted"' in manager
    assert "local_llama_cpp" in manager
    assert "def test_inference" in manager
    assert "def deactivate" in manager
    assert 'parts[1] not in {"install", "activate", "test", "stop"}' in BRIDGE
    assert 'self._public_guard(csrf=True)' in BRIDGE
    assert 'owner_password.owner_account_exists() and owner is None' in BRIDGE
    assert 'action != "install" and owner is not None' in BRIDGE
    assert 'model_switch_blocked_by_active_mission' in BRIDGE
    assert '_desktop_model_manager().test_inference()' in BRIDGE
    assert '_desktop_model_manager().deactivate()' in BRIDGE
    assert "renderModelCards" in APP
    assert "تنزيل وتثبيت" in APP
    assert "تشغيل / تبديل إلى هذا النموذج" in APP
    assert "النماذج الموصى بها لهذا الجهاز" in APP
    assert "قد تكون أكبر من ذاكرة هذا الجهاز" in APP
    assert "اختبار الاستدلال المحلي الحقيقي" in APP
    assert 'f"{ROOT / \'agent\' / \'local_runtime\' / \'catalog.json\'}{separator}agent/local_runtime"' in Path("scripts/build_desktop_backend.py").read_text(encoding="utf-8")
    assert 'f"{ROOT / \'VERSION\'}{separator}."' in Path("scripts/build_desktop_backend.py").read_text(encoding="utf-8")


def test_installer_and_exact_sha_workflow_build_a_private_artifact_not_a_release():
    build = PACKAGE["build"]
    targets = [item["target"] for item in build["win"]["target"]]
    assert targets == ["nsis"]
    assert build["extraResources"][0]["to"] == "backend"
    assert build["extraResources"][1]["to"] == "llama"
    assert build["nsis"]["allowToChangeInstallationDirectory"] is True
    assert PACKAGE["version"] == "5.2.0-rc1"
    assert "work/windows-native-local-llm" in WORKFLOW
    assert "windows-latest" in WORKFLOW
    assert "python -m pytest -q" in WORKFLOW
    assert "npm ci --no-audit --no-fund" in WORKFLOW
    assert "npm audit --audit-level=high" in WORKFLOW
    assert "scripts/download_llama_runtime.py" in WORKFLOW
    assert "scripts/build_desktop_backend.py" in WORKFLOW
    assert "scripts/write_installer_manifest.py" in WORKFLOW
    assert "Get-Content -LiteralPath VERSION -Raw" in WORKFLOW
    assert "steps.candidate-version.outputs.version" in WORKFLOW
    assert "CyberSentinel-v${{ steps.candidate-version.outputs.version }}.exe" in WORKFLOW
    assert "--parent-tested-commit" not in WORKFLOW
    assert "actions/upload-artifact@v4" in WORKFLOW
    assert "contents: read" in WORKFLOW
    assert "release:" not in WORKFLOW
    assert "git push" not in WORKFLOW
    assert Path("desktop/package-lock.json").is_file()
