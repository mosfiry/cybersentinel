#!/usr/bin/env python3
"""Write a SHA-256 sidecar and build provenance manifest for a Windows installer."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_output(*command: str) -> str | None:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return (result.stdout or result.stderr).strip()


def python_packages() -> list[str] | None:
    output = command_output(sys.executable, "-m", "pip", "freeze")
    return sorted(line for line in output.splitlines() if line) if output is not None else None


def normalize_acceptance_status(value: str | None) -> str:
    normalized = (value or "NOT_RUN").strip().upper()
    if normalized in {"SUCCESS", "PASS", "PASSED"}:
        return "PASS"
    if normalized in {"FAILURE", "FAIL", "FAILED"}:
        return "FAIL"
    return normalized or "NOT_RUN"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True, help="Full 40-character lowercase Git SHA for the build")
    parser.add_argument("--parent-tested-commit", help="Full SHA of the previously tested product-code commit")
    parser.add_argument("--installer-name", help="Installer filename; defaults to the historical CyberSentinel-Setup name")
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        raise SystemExit("source_commit_must_be_full_lowercase_git_sha")
    if args.parent_tested_commit and not re.fullmatch(r"[0-9a-f]{40}", args.parent_tested_commit):
        raise SystemExit("parent_tested_commit_must_be_full_lowercase_git_sha")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", args.version):
        raise SystemExit("version_must_be_semver")

    installer_name = args.installer_name or f"CyberSentinel-Setup-{args.version}.exe"
    if (
        Path(installer_name).name != installer_name
        or "/" in installer_name
        or "\\" in installer_name
        or not installer_name.lower().endswith(".exe")
    ):
        raise SystemExit("installer_name_must_be_a_plain_exe_filename")

    directory = args.directory.resolve()
    installer = directory / installer_name
    if not installer.is_file() or installer.stat().st_size <= 0:
        raise SystemExit(f"installer_missing_or_empty:{installer}")

    repo_root = Path(__file__).resolve().parents[1]
    canonical_version = (repo_root / "VERSION").read_text(encoding="ascii").strip()
    if args.version != canonical_version:
        raise SystemExit("manifest_version_does_not_match_repository_VERSION")
    package_path = repo_root / "desktop" / "package.json"
    lock_path = repo_root / "desktop" / "package-lock.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if package.get("version") != canonical_version:
        raise SystemExit("desktop_package_version_does_not_match_repository_VERSION")
    if (
        lock.get("version") != canonical_version
        or lock.get("packages", {}).get("", {}).get("version") != canonical_version
    ):
        raise SystemExit("desktop_package_lock_version_does_not_match_repository_VERSION")
    digest = sha256(installer)
    size_bytes = installer.stat().st_size
    (directory / f"{installer.name}.sha256").write_text(
        f"{digest}  {installer.name}\n", encoding="ascii"
    )

    run_id = os.getenv("GITHUB_RUN_ID")
    repository = os.getenv("GITHUB_REPOSITORY")
    server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    workflow_run_url = f"{server_url}/{repository}/actions/runs/{run_id}" if repository and run_id else None
    build = package.get("devDependencies", {})
    tool_versions = {
        "python": platform.python_version(),
        "pip": command_output(sys.executable, "-m", "pip", "--version"),
        "node": command_output("node", "--version"),
        "npm": command_output("npm", "--version"),
        "electron": build.get("electron"),
        "electron_builder": build.get("electron-builder"),
        "python_packages": python_packages(),
    }
    runner = {
        "os": os.getenv("RUNNER_OS", platform.system()),
        "architecture": os.getenv("RUNNER_ARCH", platform.machine()),
        "image_os": os.getenv("ImageOS"),
        "image_version": os.getenv("ImageVersion"),
        "platform": platform.platform(),
    }
    acceptance = normalize_acceptance_status(os.getenv("CYBERSENTINEL_WINDOWS_RUNNER_ACCEPTANCE"))
    preserved_candidate_acceptance = normalize_acceptance_status(
        os.getenv("CYBERSENTINEL_WINDOWS_PRESERVED_CANDIDATE_ACCEPTANCE")
    )
    preserved_candidate_full_mission = normalize_acceptance_status(
        os.getenv("CYBERSENTINEL_WINDOWS_PRESERVED_CANDIDATE_FULL_MISSION")
    )
    installed_ui_acceptance = normalize_acceptance_status(
        os.getenv("CYBERSENTINEL_WINDOWS_INSTALLED_UI_ACCEPTANCE")
    )
    full_mission_acceptance = normalize_acceptance_status(
        os.getenv("CYBERSENTINEL_WINDOWS_FULL_MISSION_E2E_ACCEPTANCE")
    )
    source_tree_e2e_supplemental = normalize_acceptance_status(
        os.getenv("CYBERSENTINEL_WINDOWS_SOURCE_TREE_E2E_SUPPLEMENTAL")
    )

    manifest: dict[str, Any] = {
        "manifest_schema_version": 1,
        "product": "CyberSentinel Desktop",
        "version": args.version,
        "package_product_name": package.get("productName"),
        "source_commit": args.source_commit,
        "parent_tested_product_code_commit": args.parent_tested_commit,
        "source_branch": os.getenv("GITHUB_REF_NAME"),
        "installer": installer.name,
        "size_bytes": size_bytes,
        "sha256": digest,
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "workflow": {
            "name": os.getenv("GITHUB_WORKFLOW"),
            "run_id": run_id,
            "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
            "run_url": workflow_run_url,
            "ref": os.getenv("GITHUB_REF"),
            "repository": repository,
        },
        "build_environment": {
            "runner": runner,
            "tool_versions": tool_versions,
            "package_lock_sha256": sha256(lock_path) if lock_path.is_file() else None,
        },
        "acceptance": {
            "windows_runner_acceptance_overall": acceptance,
            "windows_runner_backend_core_real_model": full_mission_acceptance,
            "windows_runner_preserved_candidate_installed_ui_qwen_owner_full_mission_baseline": preserved_candidate_acceptance,
            "windows_runner_preserved_candidate_full_mission": preserved_candidate_full_mission,
            "windows_runner_installed_desktop_ui_qwen_owner_auth": installed_ui_acceptance,
            "windows_runner_full_local_qwen_mission_e2e": full_mission_acceptance,
            "windows_runner_source_tree_full_e2e_supplemental_not_installed_backend": source_tree_e2e_supplemental,
            "windows_runner_scope": (
                "Native windows-latest runner: scripts/windows_installer_acceptance.ps1 installs and launches the exact installer; "
                "scripts/windows_desktop_acceptance.py drives the installed Electron first-run hardware/model manager, Qwen3 4B "
                "download/activation/real local inference, disposable Owner creation/login and invalid-password rejection, and a bounded "
                "Mission through the installed app's public UI/API and bundled backend (local project test, Research/Hypothesis, "
                "Evidence, Validator, Finding, Report, persisted pause/reload/resume, and a 300-second wall-clock guard). "
                "The separate scripts/run_full_e2e_gate_acceptance.py is checkout-source supplemental coverage for loopback Browser/MCP "
                "and Multi-Agent; it is not evidence that those advanced paths ran inside the installed backend. "
                "Hosted Windows UI is automated/non-human-interactive."
            ),
            "manual_windows_installer_gui_close_reopen": "NOT TESTED — hosted runner has no human interactive desktop session; installed UI is inspected with Playwright CDP",
        },
        "distribution": "GitHub Actions workflow artifact; no GitHub Release or tag created",
        "release_state": {
            "github_release_created": False,
            "git_tag_created": False,
            "final_release_created": False,
            "v5_1_0_modified": False,
        },
        "reproducibility": {
            "claim": "NOT CLAIMED",
            "limits": [
                "The windows-latest runner label is mutable; ImageOS and ImageVersion are recorded for this build only.",
                "The exact Python and Node tool versions and installed Python packages are recorded, but platform images and external build inputs are not frozen as a hermetic toolchain.",
                "The build downloads external runtime inputs; byte-for-byte reproducibility is not asserted.",
            ],
        },
    }
    (directory / "installer-manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"{installer.name}: {digest} ({size_bytes} bytes)", flush=True)
    print(f"Windows runner backend/core acceptance: {acceptance}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
