from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import tempfile
from typing import Any, BinaryIO

FORMAT = "cybersentinel-state-archive"
VERSION = 1
MANIFEST_NAME = "manifest.json"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_TOTAL_BYTES = 1 << 40
RESTORE_PREFIX = ".cybersentinel-restore-stage-"


class StateArchiveError(RuntimeError):
    """A sanitized failure while validating or restoring a state archive."""


def _root_path(path: Path, *, create: bool = False) -> Path:
    root = Path(path).expanduser().absolute()
    try:
        info = root.lstat()
    except FileNotFoundError:
        if not create:
            raise StateArchiveError("state_directory_missing")
        root.mkdir(parents=True, mode=0o700)
        info = root.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise StateArchiveError("state_directory_not_real_directory")
    return root


def _safe_relative(raw: Any) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise StateArchiveError("unsafe_archive_path")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or str(path) != raw
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0].startswith(RESTORE_PREFIX)
    ):
        raise StateArchiveError("unsafe_archive_path")
    return path


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise StateArchiveError("state_file_open_failed") from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise StateArchiveError("state_contains_non_regular_file")
    return fd, info


def _unchanged(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
    )


def _inventory(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirnames.sort()
        filenames.sort()
        for name in tuple(dirnames):
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise StateArchiveError("state_contains_symlink")
            if not stat.S_ISDIR(info.st_mode):
                raise StateArchiveError("state_contains_non_directory")
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative)
            entries.append(
                {"path": relative, "kind": "directory", "size": 0, "sha256": "", "mode": stat.S_IMODE(info.st_mode)}
            )
        for name in filenames:
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise StateArchiveError("state_contains_symlink")
            if not stat.S_ISREG(info.st_mode):
                raise StateArchiveError("state_contains_non_regular_file")
            relative = path.relative_to(root).as_posix()
            _safe_relative(relative)
            fd, opened = _open_regular(path)
            digest = hashlib.sha256()
            size = 0
            try:
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                after = os.fstat(fd)
                if not _unchanged(opened, after) or size != opened.st_size:
                    raise StateArchiveError("state_changed_during_backup")
            finally:
                os.close(fd)
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES:
                raise StateArchiveError("state_exceeds_archive_limit")
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "size": size,
                    "sha256": digest.hexdigest(),
                    "mode": stat.S_IMODE(opened.st_mode),
                }
            )
    if len(entries) > MAX_ENTRIES:
        raise StateArchiveError("state_has_too_many_entries")
    entries.sort(key=lambda item: (len(PurePosixPath(item["path"]).parts), item["path"]))
    return entries


def _manifest(root: Path) -> dict[str, Any]:
    root = _root_path(root)
    entries = _inventory(root)
    return {
        "format": FORMAT,
        "version": VERSION,
        "entries": entries,
        "total_bytes": sum(item["size"] for item in entries),
    }


class _HashingReader:
    def __init__(self, source: BinaryIO):
        self.source = source
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, amount: int = -1) -> bytes:
        chunk = self.source.read(amount)
        self.digest.update(chunk)
        self.size += len(chunk)
        return chunk


def backup_state(state_root: Path, output: BinaryIO) -> dict[str, Any]:
    root = _root_path(state_root)
    manifest = _manifest(root)
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise StateArchiveError("archive_manifest_too_large")
    try:
        with tarfile.open(fileobj=output, mode="w|gz", compresslevel=6) as archive:
            item = tarfile.TarInfo(MANIFEST_NAME)
            item.size = len(encoded)
            item.mode = 0o600
            item.mtime = 0
            archive.addfile(item, io.BytesIO(encoded))
            for record in manifest["entries"]:
                path = root.joinpath(*PurePosixPath(record["path"]).parts)
                info = tarfile.TarInfo(f"state/{record['path']}")
                info.mode = record["mode"]
                info.mtime = 0
                if record["kind"] == "directory":
                    current = path.lstat()
                    if not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode):
                        raise StateArchiveError("state_changed_during_backup")
                    info.type = tarfile.DIRTYPE
                    info.size = 0
                    archive.addfile(info)
                    continue
                fd, opened = _open_regular(path)
                if opened.st_size != record["size"]:
                    os.close(fd)
                    raise StateArchiveError("state_changed_during_backup")
                reader = _HashingReader(os.fdopen(fd, "rb", closefd=True))
                try:
                    info.type = tarfile.REGTYPE
                    info.size = record["size"]
                    archive.addfile(info, reader)
                    after = os.fstat(reader.source.fileno())
                    if (
                        reader.size != record["size"]
                        or reader.digest.hexdigest() != record["sha256"]
                        or not _unchanged(opened, after)
                    ):
                        raise StateArchiveError("state_changed_during_backup")
                finally:
                    reader.source.close()
    except StateArchiveError:
        raise
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise StateArchiveError("archive_write_failed") from exc
    return _summary(manifest["entries"])


def _summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    files = [item for item in entries if item["kind"] == "file"]
    return {
        "valid": True,
        "entries": len(entries),
        "files": len(files),
        "directories": len(entries) - len(files),
        "total_bytes": sum(int(item["size"]) for item in files),
    }


def _validate_manifest(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or value.get("format") != FORMAT or value.get("version") != VERSION:
        raise StateArchiveError("archive_format_unsupported")
    entries = value.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise StateArchiveError("archive_manifest_invalid")
    validated: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    total = 0
    for item in entries:
        if not isinstance(item, dict):
            raise StateArchiveError("archive_manifest_invalid")
        path = _safe_relative(item.get("path"))
        kind = item.get("kind")
        size = item.get("size")
        mode = item.get("mode")
        digest = item.get("sha256")
        if (
            kind not in {"directory", "file"}
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or isinstance(mode, bool)
            or not isinstance(mode, int)
            or mode < 0
            or mode > 0o777
        ):
            raise StateArchiveError("archive_manifest_invalid")
        if kind == "directory":
            if size != 0 or digest != "":
                raise StateArchiveError("archive_manifest_invalid")
        else:
            if not isinstance(digest, str) or len(digest) != 64:
                raise StateArchiveError("archive_manifest_invalid")
            try:
                int(digest, 16)
            except ValueError as exc:
                raise StateArchiveError("archive_manifest_invalid") from exc
            total += size
            if total > MAX_TOTAL_BYTES:
                raise StateArchiveError("archive_exceeds_size_limit")
        if str(path) in seen:
            raise StateArchiveError("archive_manifest_duplicate_path")
        for parent in path.parents:
            if str(parent) == ".":
                continue
            if seen.get(str(parent)) != "directory":
                raise StateArchiveError("archive_manifest_parent_missing")
        seen[str(path)] = kind
        validated.append(
            {"path": str(path), "kind": kind, "size": size, "sha256": digest, "mode": mode}
        )
    expected_order = sorted(
        validated,
        key=lambda item: (len(PurePosixPath(item["path"]).parts), item["path"]),
    )
    if validated != expected_order or value.get("total_bytes") != total:
        raise StateArchiveError("archive_manifest_order_or_size_invalid")
    return validated


def _read_manifest(archive: tarfile.TarFile) -> list[dict[str, Any]]:
    member = archive.next()
    if (
        member is None
        or member.name != MANIFEST_NAME
        or not member.isfile()
        or member.size < 0
        or member.size > MAX_MANIFEST_BYTES
    ):
        raise StateArchiveError("archive_manifest_missing_or_invalid")
    stream = archive.extractfile(member)
    if stream is None:
        raise StateArchiveError("archive_manifest_unreadable")
    try:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    finally:
        stream.close()
    if len(raw) != member.size or len(raw) > MAX_MANIFEST_BYTES:
        raise StateArchiveError("archive_manifest_size_invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateArchiveError("archive_manifest_invalid") from exc
    return _validate_manifest(value)


def _copy_and_hash(source: BinaryIO, destination: BinaryIO | None, expected_size: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > expected_size or size > MAX_TOTAL_BYTES:
            raise StateArchiveError("archive_member_size_exceeded")
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
    if size != expected_size:
        raise StateArchiveError("archive_member_size_mismatch")
    return size, digest.hexdigest()


def _consume_archive(
    input_stream: BinaryIO,
    *,
    staging_root: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        with tarfile.open(fileobj=input_stream, mode="r|gz") as archive:
            entries = _read_manifest(archive)
            directories: list[tuple[Path, int]] = []
            for record in entries:
                member = archive.next()
                expected_name = f"state/{record['path']}"
                if member is None or member.name != expected_name:
                    raise StateArchiveError("archive_member_order_invalid")
                if record["kind"] == "directory":
                    if not member.isdir() or member.size != 0:
                        raise StateArchiveError("archive_member_type_invalid")
                    if staging_root is not None:
                        target = staging_root.joinpath(*PurePosixPath(record["path"]).parts)
                        target.mkdir(mode=0o700)
                        directories.append((target, record["mode"]))
                    continue
                if not member.isfile() or member.size != record["size"]:
                    raise StateArchiveError("archive_member_type_or_size_invalid")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise StateArchiveError("archive_member_unreadable")
                destination: BinaryIO | None = None
                fd = -1
                if staging_root is not None:
                    target = staging_root.joinpath(*PurePosixPath(record["path"]).parts)
                    if not target.parent.is_dir() or target.parent.is_symlink():
                        raise StateArchiveError("archive_parent_not_directory")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                    try:
                        fd = os.open(target, flags, 0o600)
                    except OSError as exc:
                        raise StateArchiveError("restore_file_create_failed") from exc
                    destination = os.fdopen(fd, "wb", closefd=True)
                try:
                    with extracted:
                        size, digest = _copy_and_hash(extracted, destination, record["size"])
                    if destination is not None:
                        destination.flush()
                        os.fchmod(destination.fileno(), record["mode"])
                        os.fsync(destination.fileno())
                finally:
                    if destination is not None:
                        destination.close()
                if size != record["size"] or digest != record["sha256"]:
                    raise StateArchiveError("archive_member_digest_mismatch")
            if archive.next() is not None:
                raise StateArchiveError("archive_contains_unlisted_members")
    except StateArchiveError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError) as exc:
        raise StateArchiveError("archive_read_failed") from exc
    if staging_root is not None:
        for target, mode in reversed(directories):
            os.chmod(target, mode, follow_symlinks=False)
    return entries, _summary(entries)


def verify_archive(input_stream: BinaryIO) -> dict[str, Any]:
    _entries, summary = _consume_archive(input_stream)
    return summary


def restore_state(input_stream: BinaryIO, state_root: Path) -> dict[str, Any]:
    root = _root_path(state_root, create=True)
    try:
        if any(root.iterdir()):
            raise StateArchiveError("restore_target_not_empty")
        staging = Path(tempfile.mkdtemp(prefix=RESTORE_PREFIX, dir=root))
        os.chmod(staging, 0o700)
    except StateArchiveError:
        raise
    except OSError as exc:
        raise StateArchiveError("restore_staging_create_failed") from exc
    try:
        entries, summary = _consume_archive(input_stream, staging_root=staging)
        for child in sorted(staging.iterdir(), key=lambda item: item.name):
            destination = root / child.name
            if destination.exists() or destination.is_symlink():
                raise StateArchiveError("restore_target_changed")
            os.replace(child, destination)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return summary
    except StateArchiveError:
        raise
    except OSError as exc:
        raise StateArchiveError("restore_commit_failed") from exc
    finally:
        try:
            shutil.rmtree(staging)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _main() -> int:
    parser = argparse.ArgumentParser(description="Verify and restore CyberSentinel state archives")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path(os.environ.get("CYBERSENTINEL_STATE_DIR", "/var/lib/cybersentinel")),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("backup", help="write a verified archive to stdout")
    subparsers.add_parser("verify", help="verify an archive read from stdin")
    subparsers.add_parser("restore", help="restore stdin archive to an empty state directory")
    args = parser.parse_args()
    try:
        if args.command == "backup":
            backup_state(args.state_dir, sys.stdout.buffer)
        elif args.command == "verify":
            print(json.dumps(verify_archive(sys.stdin.buffer), sort_keys=True))
        else:
            print(json.dumps(restore_state(sys.stdin.buffer, args.state_dir), sort_keys=True))
    except StateArchiveError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
