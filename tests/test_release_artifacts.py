from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from core.version import VERSION as APPLICATION_VERSION
from scripts.package_release import (
    ReleaseArtifactError,
    build_release,
    verify_release,
)

ROOT = Path(__file__).resolve().parents[1]


def _docker_save_fixture(path: Path) -> None:
    manifest = json.dumps(
        [{"Config": "config.json", "RepoTags": [f"cybersentinel-runtime:{APPLICATION_VERSION}"], "Layers": []}]
    ).encode("utf-8")
    with tarfile.open(path, mode="w") as archive:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        archive.addfile(info, io.BytesIO(manifest))
        config = b"{}"
        info = tarfile.TarInfo("config.json")
        info.size = len(config)
        archive.addfile(info, io.BytesIO(config))


def test_release_version_matches_runtime_version() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == APPLICATION_VERSION


def test_release_bundle_contains_versioned_image_and_verified_payload(tmp_path: Path) -> None:
    image_tar = tmp_path / "docker-save.tar"
    _docker_save_fixture(image_tar)
    output = tmp_path / "artifacts"

    summary = build_release(
        root=ROOT,
        image_tar=image_tar,
        output_dir=output,
        commit="a" * 40,
    )

    archive_path = output / f"cybersentinel-{APPLICATION_VERSION}-release.tar.gz"
    checksum_path = Path(str(archive_path) + ".sha256")
    assert summary["status"] == "PASS"
    assert summary["version"] == APPLICATION_VERSION
    assert summary["source_commit"] == "a" * 40
    assert archive_path.is_file()
    assert checksum_path.is_file()
    assert verify_release(archive_path)["release_archive_sha256"] == hashlib.sha256(
        archive_path.read_bytes()
    ).hexdigest()

    with tarfile.open(archive_path, mode="r:gz") as archive:
        names = set(archive.getnames())
    root_name = f"cybersentinel-{APPLICATION_VERSION}/"
    for relative in (
        "compose.yaml",
        ".env.example",
        "VERSION",
        "RELEASE_NOTES.md",
        "release-metadata.json",
        "SHA256SUMS",
        "images/cybersentinel-runtime-5.0.0.tar",
        "scripts/install_compose.sh",
        "scripts/backup_state.sh",
        "scripts/restore_state.sh",
        "scripts/state_archive.py",
        "desktop/README.md",
        "desktop/main.js",
        "desktop/package.json",
        "desktop/package-lock.json",
        "docs/DESKTOP_ARCHITECTURE.md",
        "docs/DESKTOP_BACKEND_CONTRACT.md",
    ):
        assert f"{root_name}{relative}" in names
    assert not any("/diagnostics/" in name or "/tests/" in name for name in names)
    assert not any(name.endswith("/.env") or "/secrets/" in name for name in names)


def test_release_bundle_is_reproducible_for_identical_inputs(tmp_path: Path) -> None:
    image_tar = tmp_path / "docker-save.tar"
    _docker_save_fixture(image_tar)
    first = build_release(
        root=ROOT,
        image_tar=image_tar,
        output_dir=tmp_path / "first",
        commit="b" * 40,
    )
    second = build_release(
        root=ROOT,
        image_tar=image_tar,
        output_dir=tmp_path / "second",
        commit="b" * 40,
    )
    first_archive = tmp_path / "first" / f"cybersentinel-{APPLICATION_VERSION}-release.tar.gz"
    second_archive = tmp_path / "second" / f"cybersentinel-{APPLICATION_VERSION}-release.tar.gz"
    assert first["release_archive_sha256"] == second["release_archive_sha256"]
    assert first_archive.read_bytes() == second_archive.read_bytes()


def test_release_bundle_refuses_a_symlinked_docker_archive(tmp_path: Path) -> None:
    image_tar = tmp_path / "docker-save.tar"
    _docker_save_fixture(image_tar)
    link = tmp_path / "image-link.tar"
    link.symlink_to(image_tar)

    with pytest.raises(ReleaseArtifactError, match="regular non-symlink"):
        build_release(
            root=ROOT,
            image_tar=link,
            output_dir=tmp_path / "artifacts",
            commit="c" * 40,
        )


def test_release_outer_checksum_detects_tampering(tmp_path: Path) -> None:
    image_tar = tmp_path / "docker-save.tar"
    _docker_save_fixture(image_tar)
    output = tmp_path / "artifacts"
    build_release(root=ROOT, image_tar=image_tar, output_dir=output, commit="d" * 40)
    archive_path = output / f"cybersentinel-{APPLICATION_VERSION}-release.tar.gz"
    archive_path.write_bytes(archive_path.read_bytes() + b"tamper")

    with pytest.raises(ReleaseArtifactError, match="SHA-256 mismatch"):
        verify_release(archive_path)


def test_release_operator_shell_scripts_parse_and_are_executable() -> None:
    for name in ("install_compose.sh", "backup_state.sh", "restore_state.sh"):
        path = ROOT / "scripts" / name
        assert path.stat().st_mode & 0o111
        result = subprocess.run(
            ["bash", "-n", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_backup_and_restore_wrappers_preserve_data_recovery_boundaries() -> None:
    backup = (ROOT / "scripts" / "backup_state.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts" / "restore_state.sh").read_text(encoding="utf-8")

    assert '"${compose[@]}" stop bridge mission-worker' in backup
    assert "/app/scripts/state_archive.py backup" in backup
    assert "/app/scripts/state_archive.py verify" in backup
    assert 'trap restore_service_state EXIT' in backup
    assert '"${compose[@]}" down --volumes' not in backup
    assert '"${restore_compose[@]}" run --rm --no-deps -T --entrypoint python workspace-init' in restore
    assert "/app/scripts/state_archive.py verify" in restore
    assert "/app/scripts/state_archive.py restore" in restore
    assert 'docker volume inspect "$volume"' in restore
    assert "refusing to restore into the active Compose project" in restore
    assert '"${restore_compose[@]}" up ' not in restore
