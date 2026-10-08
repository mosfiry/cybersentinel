from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from scripts.write_installer_manifest import main
from core.version import VERSION as REPOSITORY_VERSION


def test_installer_manifest_binds_digest_and_source_commit(tmp_path: Path, monkeypatch) -> None:
    installer = tmp_path / f"CyberSentinel-Setup-{REPOSITORY_VERSION}.exe"
    installer.write_bytes(b"fixture-nsis-installer")
    source_commit = "2ef29b7de9eb43a7880223d0d256699eac2d4945"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write_installer_manifest.py",
            str(tmp_path),
            "--version",
            REPOSITORY_VERSION,
            "--source-commit",
            source_commit,
        ],
    )

    assert main() == 0

    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    manifest = json.loads((tmp_path / "installer-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == REPOSITORY_VERSION
    assert manifest["source_commit"] == source_commit
    assert manifest["sha256"] == digest
    assert manifest["size_bytes"] == installer.stat().st_size
    assert manifest["distribution"] == "GitHub Actions workflow artifact; no GitHub Release or tag created"
    assert (tmp_path / f"{installer.name}.sha256").read_text(encoding="ascii") == f"{digest}  {installer.name}\n"


def test_installer_manifest_records_separate_windows_acceptance_gates(tmp_path: Path, monkeypatch) -> None:
    installer = tmp_path / f"CyberSentinel-Setup-{REPOSITORY_VERSION}.exe"
    installer.write_bytes(b"fixture-nsis-installer")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write_installer_manifest.py",
            str(tmp_path),
            "--version",
            REPOSITORY_VERSION,
            "--source-commit",
            "2ef29b7de9eb43a7880223d0d256699eac2d4945",
        ],
    )
    monkeypatch.setenv("CYBERSENTINEL_WINDOWS_RUNNER_ACCEPTANCE", "PASSED")
    monkeypatch.setenv("CYBERSENTINEL_WINDOWS_PRESERVED_CANDIDATE_ACCEPTANCE", "PASS")
    monkeypatch.setenv("CYBERSENTINEL_WINDOWS_PRESERVED_CANDIDATE_FULL_MISSION", "FAIL")
    monkeypatch.setenv("CYBERSENTINEL_WINDOWS_INSTALLED_UI_ACCEPTANCE", "PASS")
    monkeypatch.setenv("CYBERSENTINEL_WINDOWS_FULL_MISSION_E2E_ACCEPTANCE", "PASS")
    monkeypatch.setenv("CYBERSENTINEL_WINDOWS_SOURCE_TREE_E2E_SUPPLEMENTAL", "PASS")

    assert main() == 0

    manifest = json.loads((tmp_path / "installer-manifest.json").read_text(encoding="utf-8"))
    acceptance = manifest["acceptance"]
    assert acceptance["windows_runner_acceptance_overall"] == "PASS"
    assert acceptance["windows_runner_preserved_candidate_installed_ui_qwen_owner_full_mission_baseline"] == "PASS"
    assert acceptance["windows_runner_preserved_candidate_full_mission"] == "FAIL"
    assert acceptance["windows_runner_installed_desktop_ui_qwen_owner_auth"] == "PASS"
    assert acceptance["windows_runner_full_local_qwen_mission_e2e"] == "PASS"
    assert acceptance["windows_runner_source_tree_full_e2e_supplemental_not_installed_backend"] == "PASS"


def test_installer_manifest_rejects_non_full_source_sha(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write_installer_manifest.py",
            str(tmp_path),
            "--version",
            REPOSITORY_VERSION,
            "--source-commit",
            "2ef29b7",
        ],
    )

    with pytest.raises(SystemExit, match="source_commit_must_be_full_lowercase_git_sha"):
        main()


def test_installer_manifest_rejects_candidate_version_mismatch(tmp_path: Path, monkeypatch) -> None:
    installer = tmp_path / "CyberSentinel-Setup-5.1.0.exe"
    installer.write_bytes(b"fixture-installer")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write_installer_manifest.py",
            str(tmp_path),
            "--version",
            "5.1.0",
            "--source-commit",
            "2ef29b7de9eb43a7880223d0d256699eac2d4945",
        ],
    )

    with pytest.raises(SystemExit, match="manifest_version_does_not_match_repository_VERSION"):
        main()
