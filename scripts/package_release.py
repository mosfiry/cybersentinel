#!/usr/bin/env python3
"""Build and verify an unpublished, checksummed CyberSentinel release bundle."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_FILES = (
    ".dockerignore",
    ".env.example",
    "Dockerfile",
    "README.md",
    "RELEASE_NOTES.md",
    "VERSION",
    "compose.yaml",
    "requirements-runtime.txt",
    "docs/OPERATIONS.md",
    "docs/SECURITY_MODEL.md",
    "docs/DESKTOP_ARCHITECTURE.md",
    "docs/DESKTOP_BACKEND_CONTRACT.md",
    "docs/LOCAL_MODEL_ARTIFACTS.md",
    "scripts/backup_state.sh",
    "scripts/install_compose.sh",
    "scripts/package_release.py",
    "scripts/prepare_compose_secrets.py",
    "scripts/restore_state.sh",
    "scripts/state_archive.py",
)
EXCLUDED_TOP_LEVEL = {".github", "diagnostics", "docs", "evaluation", "tests"}
EXCLUDED_ANY_LEVEL = {"diagnostics", "tests"}
EXCLUDED_FILES = {
    ".env.agent.example",
    "firebase.json",
    "pytest.ini",
    "requirements.txt",
    "scripts/verify_container_contract.py",
}
FORBIDDEN_PATH_SUFFIXES = (".pem", ".key", ".db", ".sqlite", ".sqlite3")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CHUNK_SIZE = 1024 * 1024


class ReleaseArtifactError(ValueError):
    """Raised when a release input or artifact violates its contract."""


def _regular_file(path: Path, *, description: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseArtifactError(f"{description} is missing or inaccessible: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ReleaseArtifactError(f"{description} must be a regular non-symlink file: {path}")
    return info


def _sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    _regular_file(path, description="file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        return _sha256_stream(stream)


def _verify_docker_save_archive(path: Path, expected_tag: str) -> None:
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            names: set[str] = set()
            for member in members:
                name = PurePosixPath(member.name)
                if name.is_absolute() or any(part in {".", ".."} for part in name.parts):
                    raise ReleaseArtifactError("Docker image archive contains an unsafe member path")
                if not (member.isfile() or member.isdir()):
                    raise ReleaseArtifactError("Docker image archive contains a link or special file")
                if member.name in names:
                    raise ReleaseArtifactError("Docker image archive contains a duplicate member")
                names.add(member.name)
            manifest_member = next((item for item in members if item.name == "manifest.json"), None)
            if manifest_member is None or not manifest_member.isfile():
                raise ReleaseArtifactError("Docker image archive is missing manifest.json")
            manifest_stream = archive.extractfile(manifest_member)
            if manifest_stream is None:
                raise ReleaseArtifactError("Docker image manifest cannot be read")
            with manifest_stream:
                manifest = json.load(manifest_stream)
    except (tarfile.TarError, OSError, json.JSONDecodeError) as exc:
        raise ReleaseArtifactError("Docker image archive is not a readable Docker save tar") from exc

    if not isinstance(manifest, list) or not manifest:
        raise ReleaseArtifactError("Docker image manifest must contain at least one image")
    matched = False
    for record in manifest:
        if not isinstance(record, dict):
            raise ReleaseArtifactError("Docker image manifest contains an invalid entry")
        tags = record.get("RepoTags") or []
        if expected_tag in tags:
            matched = True
        referenced = [record.get("Config"), *record.get("Layers", [])]
        if any(not isinstance(name, str) or name not in names for name in referenced):
            raise ReleaseArtifactError("Docker image manifest references a missing image layer")
    if not matched:
        raise ReleaseArtifactError(f"Docker image archive does not contain expected tag {expected_tag}")


def _read_version(root: Path) -> str:
    version_path = root / "VERSION"
    _regular_file(version_path, description="VERSION")
    version = version_path.read_text(encoding="ascii").strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ReleaseArtifactError("VERSION must contain a stable numeric MAJOR.MINOR.PATCH value")
    version_module = root / "core" / "version.py"
    if version_module.exists():
        source = version_module.read_text(encoding="utf-8")
        match = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']\s*$', source, re.MULTILINE)
        if not match or match.group(1) != version:
            raise ReleaseArtifactError("VERSION does not match core/version.py")
    return version


def _source_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    selected: set[str] = set(PAYLOAD_FILES)
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8")
        path = PurePosixPath(relative)
        if not path.parts or path.parts[0] in EXCLUDED_TOP_LEVEL or EXCLUDED_ANY_LEVEL.intersection(path.parts):
            continue
        if relative in EXCLUDED_FILES or relative.startswith(".git/"):
            continue
        if relative == ".env" or relative.startswith("secrets/") or relative.startswith("tokens/"):
            continue
        if any(relative.endswith(suffix) for suffix in FORBIDDEN_PATH_SUFFIXES):
            continue
        selected.add(relative)

    files: list[Path] = []
    for relative in sorted(selected):
        source = root / relative
        _regular_file(source, description=f"release source {relative}")
        if relative.endswith("_state.json"):
            raise ReleaseArtifactError(f"refusing state file in release source: {relative}")
        files.append(source)
    return files


def _write_checksums(bundle_root: Path) -> None:
    entries = []
    for path in sorted(item for item in bundle_root.rglob("*") if item.is_file()):
        if path.is_symlink():
            raise ReleaseArtifactError(f"symlink in release staging tree: {path}")
        relative = path.relative_to(bundle_root).as_posix()
        entries.append(f"{_sha256_file(path)}  {relative}")
    (bundle_root / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="ascii")
    os.chmod(bundle_root / "SHA256SUMS", 0o644)


def _tar_info(path: Path, archive_name: str, *, is_directory: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(archive_name + ("/" if is_directory and not archive_name.endswith("/") else ""))
    stat_info = path.lstat()
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = stat.S_IMODE(stat_info.st_mode)
    if is_directory:
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:
        if not stat.S_ISREG(stat_info.st_mode):
            raise ReleaseArtifactError(f"release source is not a regular file: {path}")
        info.type = tarfile.REGTYPE
        info.size = stat_info.st_size
    return info


def _write_deterministic_tar_gz(source_root: Path, archive_path: Path, bundle_name: str) -> None:
    with archive_path.open("xb") as raw_output:
        with gzip.GzipFile(filename="", fileobj=raw_output, mode="wb", mtime=0, compresslevel=6) as gzip_output:
            with tarfile.open(fileobj=gzip_output, mode="w") as archive:
                archive.addfile(_tar_info(source_root, bundle_name, is_directory=True))
                for path in sorted(source_root.rglob("*")):
                    relative = path.relative_to(source_root).as_posix()
                    archive_name = f"{bundle_name}/{relative}"
                    if path.is_symlink():
                        raise ReleaseArtifactError(f"symlinks are not permitted in release bundle: {relative}")
                    if path.is_dir():
                        archive.addfile(_tar_info(path, archive_name, is_directory=True))
                    else:
                        with path.open("rb") as stream:
                            archive.addfile(_tar_info(path, archive_name, is_directory=False), stream)


def build_release(
    *, root: Path, image_tar: Path, output_dir: Path, commit: str
) -> dict[str, object]:
    root = root.resolve()
    version = _read_version(root)
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ReleaseArtifactError("source commit must be a full 40-character lowercase Git SHA")
    image_tar = image_tar.absolute()
    image_info = _regular_file(image_tar, description="Docker image archive")
    if image_info.st_size <= 0:
        raise ReleaseArtifactError("Docker image archive is empty")
    _verify_docker_save_archive(image_tar, f"cybersentinel-runtime:{version}")

    output_dir = output_dir.absolute()
    if output_dir.is_symlink():
        raise ReleaseArtifactError("output directory must not be a symlink")
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        if output_dir.resolve().is_relative_to(root):
            raise ReleaseArtifactError("release artifacts must be written outside the source checkout")
    except AttributeError:  # Python < 3.9 compatibility guard; runtime currently requires newer Python.
        if str(output_dir.resolve()).startswith(str(root) + os.sep):
            raise ReleaseArtifactError("release artifacts must be written outside the source checkout")

    bundle_name = f"cybersentinel-{version}"
    archive_name = f"{bundle_name}-release.tar.gz"
    archive_path = output_dir / archive_name
    checksum_path = output_dir / f"{archive_name}.sha256"
    if archive_path.exists() or archive_path.is_symlink() or checksum_path.exists() or checksum_path.is_symlink():
        raise ReleaseArtifactError("refusing to overwrite an existing release artifact")

    with tempfile.TemporaryDirectory(prefix="cybersentinel-release-stage-") as temporary:
        stage_root = Path(temporary) / bundle_name
        stage_root.mkdir(mode=0o755)
        image_relative = f"images/cybersentinel-runtime-{version}.tar"
        for source in _source_files(root):
            relative = source.relative_to(root).as_posix()
            destination = stage_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            source_info = _regular_file(source, description=f"release source {relative}")
            shutil.copyfile(source, destination)
            os.chmod(destination, stat.S_IMODE(source_info.st_mode))

        image_destination = stage_root / image_relative
        image_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(image_tar, image_destination)
        os.chmod(image_destination, 0o644)
        metadata = {
            "format": "cybersentinel-release-bundle-v1",
            "product": "CyberSentinel X",
            "version": version,
            "release_status": "unpublished_candidate",
            "source_commit": commit,
            "image": {
                "tag": f"cybersentinel-runtime:{version}",
                "archive": image_relative,
                "sha256": _sha256_file(image_destination),
            },
            "publication": {"final_tag_created": False, "public_release_created": False},
        }
        (stage_root / "release-metadata.json").write_text(
            json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(stage_root / "release-metadata.json", 0o644)
        _write_checksums(stage_root)

        temporary_archive = output_dir / f".{archive_name}.{os.getpid()}.tmp"
        try:
            _write_deterministic_tar_gz(stage_root, temporary_archive, bundle_name)
            actual_outer_sha = _sha256_file(temporary_archive)
            os.replace(temporary_archive, archive_path)
            checksum_tmp = output_dir / f".{archive_name}.sha256.{os.getpid()}.tmp"
            checksum_tmp.write_text(f"{actual_outer_sha}  {archive_name}\n", encoding="ascii")
            os.chmod(checksum_tmp, 0o644)
            os.replace(checksum_tmp, checksum_path)
            summary = verify_release(archive_path)
        except Exception:
            temporary_archive.unlink(missing_ok=True)
            archive_path.unlink(missing_ok=True)
            checksum_path.unlink(missing_ok=True)
            raise
    return summary


def _safe_member_name(name: str) -> tuple[str, str]:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {".", ".."} for part in path.parts):
        raise ReleaseArtifactError(f"unsafe archive member path: {name!r}")
    if not path.parts[0].startswith("cybersentinel-"):
        raise ReleaseArtifactError(f"archive member is outside the release root: {name!r}")
    if len(path.parts) == 1:
        return path.parts[0], ""
    return path.parts[0], PurePosixPath(*path.parts[1:]).as_posix()


def _parse_sha256sums(payload: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseArtifactError("SHA256SUMS is not ASCII") from exc
    for line in lines:
        if not line:
            continue
        if len(line) < 67 or line[64:66] != "  ":
            raise ReleaseArtifactError("malformed SHA256SUMS entry")
        digest, relative = line[:64], line[66:]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReleaseArtifactError("invalid SHA-256 digest in SHA256SUMS")
        path = PurePosixPath(relative)
        if path.is_absolute() or any(part in {".", ".."} for part in path.parts) or relative in result:
            raise ReleaseArtifactError("unsafe or duplicate path in SHA256SUMS")
        result[relative] = digest
    return result


def verify_release(archive_path: Path) -> dict[str, object]:
    archive_path = archive_path.absolute()
    _regular_file(archive_path, description="release archive")
    checksum_path = Path(str(archive_path) + ".sha256")
    _regular_file(checksum_path, description="outer checksum sidecar")
    sidecar = checksum_path.read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", sidecar)
    if not match or match.group(2) != archive_path.name:
        raise ReleaseArtifactError("outer checksum sidecar has an invalid format or filename")
    outer_sha = _sha256_file(archive_path)
    if outer_sha != match.group(1):
        raise ReleaseArtifactError("release archive SHA-256 mismatch")

    file_hashes: dict[str, str] = {}
    captured: dict[str, bytes] = {}
    roots: set[str] = set()
    seen_names: set[str] = set()
    try:
        archive = tarfile.open(archive_path, mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ReleaseArtifactError("release archive is not a readable gzip tar") from exc
    with archive:
        for member in archive:
            root_name, relative = _safe_member_name(member.name.rstrip("/"))
            roots.add(root_name)
            canonical = f"{root_name}/{relative}"
            if canonical in seen_names:
                raise ReleaseArtifactError(f"duplicate tar member: {canonical}")
            seen_names.add(canonical)
            if member.isdir():
                continue
            if not member.isfile():
                raise ReleaseArtifactError(f"non-regular archive member is not allowed: {canonical}")
            if any(part in {"secrets", "tokens", ".git"} for part in PurePosixPath(relative).parts):
                raise ReleaseArtifactError(f"sensitive directory in release bundle: {relative}")
            if relative == ".env" or relative.endswith("_state.json") or relative.endswith(FORBIDDEN_PATH_SUFFIXES):
                raise ReleaseArtifactError(f"sensitive file in release bundle: {relative}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ReleaseArtifactError(f"cannot read archive member: {canonical}")
            digest = hashlib.sha256()
            chunks: list[bytes] | None = [] if relative in {"SHA256SUMS", "release-metadata.json", "VERSION"} else None
            with stream:
                while True:
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
                    if chunks is not None:
                        if sum(map(len, chunks)) + len(chunk) > 1024 * 1024:
                            raise ReleaseArtifactError(f"metadata file unexpectedly large: {relative}")
                        chunks.append(chunk)
            file_hashes[relative] = digest.hexdigest()
            if chunks is not None:
                captured[relative] = b"".join(chunks)

    if len(roots) != 1:
        raise ReleaseArtifactError("release archive must contain exactly one top-level bundle directory")
    bundle_root = next(iter(roots))
    version_bytes = captured.get("VERSION", b"")
    try:
        version = version_bytes.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReleaseArtifactError("VERSION in release archive is not ASCII") from exc
    if not VERSION_PATTERN.fullmatch(version) or bundle_root != f"cybersentinel-{version}":
        raise ReleaseArtifactError("bundle root does not match its VERSION")

    required = {PurePosixPath(item).as_posix() for item in PAYLOAD_FILES}
    image_relative = f"images/cybersentinel-runtime-{version}.tar"
    required.update({image_relative, "release-metadata.json", "SHA256SUMS"})
    if not required.issubset(file_hashes):
        raise ReleaseArtifactError("release bundle is missing required files: " + ", ".join(sorted(required - set(file_hashes))))

    sums = _parse_sha256sums(captured.get("SHA256SUMS", b""))
    expected_files = set(file_hashes) - {"SHA256SUMS"}
    if set(sums) != expected_files:
        raise ReleaseArtifactError("SHA256SUMS does not cover exactly the bundle payload files")
    for relative, digest in sums.items():
        if file_hashes[relative] != digest:
            raise ReleaseArtifactError(f"bundle SHA-256 mismatch: {relative}")

    try:
        metadata = json.loads(captured.get("release-metadata.json", b"{}"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReleaseArtifactError("release metadata is invalid JSON") from exc
    image = metadata.get("image", {})
    source_commit = metadata.get("source_commit", "")
    if (
        metadata.get("format") != "cybersentinel-release-bundle-v1"
        or metadata.get("product") != "CyberSentinel X"
        or metadata.get("version") != version
        or metadata.get("release_status") != "unpublished_candidate"
        or not COMMIT_PATTERN.fullmatch(source_commit)
        or image.get("tag") != f"cybersentinel-runtime:{version}"
        or image.get("archive") != image_relative
        or image.get("sha256") != file_hashes[image_relative]
        or metadata.get("publication") != {"final_tag_created": False, "public_release_created": False}
    ):
        raise ReleaseArtifactError("release metadata does not match the bundle contents or publication boundary")

    return {
        "status": "PASS",
        "product": "CyberSentinel X",
        "version": version,
        "source_commit": source_commit,
        "file_count": len(file_hashes),
        "image_tag": image["tag"],
        "image_sha256": image["sha256"],
        "release_archive": archive_path.name,
        "release_archive_sha256": outer_sha,
        "publication": "unpublished_candidate",
    }


def _assert_clean_checkout(root: Path) -> None:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        raise ReleaseArtifactError("refusing to package a dirty source checkout")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build", help="build a release archive from a verified Docker save archive")
    build_parser.add_argument("--image-tar", type=Path, required=True)
    build_parser.add_argument("--output-dir", type=Path, required=True)
    build_parser.add_argument("--commit", required=True)
    build_parser.add_argument("--root", type=Path, default=ROOT)
    verify_parser = subparsers.add_parser("verify", help="verify outer and embedded release checksums")
    verify_parser.add_argument("archive", type=Path)
    args = parser.parse_args()

    try:
        if args.command == "build":
            _assert_clean_checkout(args.root.resolve())
            result = build_release(
                root=args.root,
                image_tar=args.image_tar,
                output_dir=args.output_dir,
                commit=args.commit,
            )
        else:
            result = verify_release(args.archive)
    except (OSError, subprocess.CalledProcessError, ReleaseArtifactError, tarfile.TarError) as exc:
        print(f"release artifact error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
