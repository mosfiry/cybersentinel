from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tarfile

import pytest

from scripts.state_archive import (
    FORMAT,
    VERSION,
    StateArchiveError,
    backup_state,
    restore_state,
    verify_archive,
)


def _archive(root: Path) -> bytes:
    output = io.BytesIO()
    backup_state(root, output)
    return output.getvalue()


def test_archive_round_trip_preserves_files_modes_and_manifest_hashes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "workspace" / "nested").mkdir(parents=True)
    (source / "intel.db").write_bytes(b"sqlite-state\x00data")
    (source / "workspace" / "nested" / "note.txt").write_text(
        "synthetic owner workspace\n", encoding="utf-8"
    )
    os.chmod(source / "intel.db", 0o600)
    os.chmod(source / "workspace", 0o700)

    packed = _archive(source)
    verified = verify_archive(io.BytesIO(packed))
    target = tmp_path / "restored"
    restored = restore_state(io.BytesIO(packed), target)

    assert verified["valid"] is True
    assert verified["files"] == 2
    assert restored == verified
    assert (target / "intel.db").read_bytes() == b"sqlite-state\x00data"
    assert (target / "workspace" / "nested" / "note.txt").read_text(
        encoding="utf-8"
    ) == "synthetic owner workspace\n"
    assert (target / "intel.db").stat().st_mode & 0o777 == 0o600
    assert (target / "workspace").stat().st_mode & 0o777 == 0o700
    assert not any(path.name.startswith(".cybersentinel-restore-stage-") for path in target.iterdir())


def test_backup_rejects_symlinks_and_non_regular_state(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir()
    (root / "real.txt").write_text("state", encoding="utf-8")
    (root / "link.txt").symlink_to(root / "real.txt")

    with pytest.raises(StateArchiveError, match="state_contains_symlink"):
        _archive(root)


def test_restore_refuses_non_empty_target_without_overwriting(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "state.txt").write_text("archive", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("do not overwrite", encoding="utf-8")

    with pytest.raises(StateArchiveError, match="restore_target_not_empty"):
        restore_state(io.BytesIO(_archive(source)), target)

    assert (target / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"


def test_archive_manifest_rejects_path_traversal_before_extraction() -> None:
    manifest = {
        "format": FORMAT,
        "version": VERSION,
        "entries": [
            {
                "path": "../outside.txt",
                "kind": "file",
                "size": 1,
                "sha256": "0" * 64,
                "mode": 0o600,
            }
        ],
        "total_bytes": 1,
    }
    encoded = json.dumps(manifest).encode("utf-8")
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(encoded)
        archive.addfile(info, io.BytesIO(encoded))
        info = tarfile.TarInfo("state/../outside.txt")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    with pytest.raises(StateArchiveError, match="unsafe_archive_path"):
        verify_archive(io.BytesIO(payload.getvalue()))


def test_archive_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "value.txt").write_text("original", encoding="utf-8")
    original = _archive(source)
    members: list[tuple[tarfile.TarInfo, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as archive:
        for member in archive:
            stream = archive.extractfile(member)
            members.append((member, stream.read() if stream is not None else b""))
    manifest = json.loads(members[0][1])
    manifest["entries"][0]["sha256"] = "0" * 64
    tampered = io.BytesIO()
    with tarfile.open(fileobj=tampered, mode="w:gz") as archive:
        for index, (member, content) in enumerate(members):
            if index == 0:
                content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            info = tarfile.TarInfo(member.name)
            info.type = member.type
            info.mode = member.mode
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content) if member.isfile() else None)

    with pytest.raises(StateArchiveError):
        verify_archive(io.BytesIO(tampered.getvalue()))
