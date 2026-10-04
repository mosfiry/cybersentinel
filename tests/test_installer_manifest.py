from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from scripts.write_installer_manifest import main


def test_installer_manifest_binds_digest_and_source_commit(tmp_path: Path, monkeypatch) -> None:
    installer = tmp_path / "CyberSentinel-Setup-5.1.0.exe"
    installer.write_bytes(b"fixture-nsis-installer")
    source_commit = "2ef29b7de9eb43a7880223d0d256699eac2d4945"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write_installer_manifest.py",
            str(tmp_path),
            "--version",
            "5.1.0",
            "--source-commit",
            source_commit,
        ],
    )

    assert main() == 0

    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    manifest = json.loads((tmp_path / "installer-manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_commit"] == source_commit
    assert manifest["sha256"] == digest
    assert manifest["size_bytes"] == installer.stat().st_size
    assert manifest["distribution"] == "GitHub Actions workflow artifact; no GitHub Release or tag created"
    assert (tmp_path / f"{installer.name}.sha256").read_text(encoding="ascii") == f"{digest}  {installer.name}\n"


def test_installer_manifest_rejects_non_full_source_sha(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "write_installer_manifest.py",
            str(tmp_path),
            "--version",
            "5.1.0",
            "--source-commit",
            "2ef29b7",
        ],
    )

    with pytest.raises(SystemExit, match="source_commit_must_be_full_lowercase_git_sha"):
        main()
